"""Exercise the production lease implementation in independent .NET processes."""
import pathlib
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET

root = pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='cdl-lease-probe-') as directory:
    probe = pathlib.Path(directory)
    project = ET.Element('Project', Sdk='Microsoft.NET.Sdk')
    properties = ET.SubElement(project, 'PropertyGroup')
    for key, value in {'OutputType': 'Exe', 'TargetFramework': 'net10.0',
                       'Nullable': 'enable', 'ImplicitUsings': 'enable',
                       'EnableDefaultCompileItems': 'false', 'RestoreLockedMode': 'false'}.items():
        ET.SubElement(properties, key).text = value
    items = ET.SubElement(project, 'ItemGroup')
    ET.SubElement(items, 'Compile', Include=str(root / 'ColDogLocker.Services/Lockers/LockerOperationLease.cs'))
    ET.SubElement(items, 'Compile', Include='Program.cs')
    ET.ElementTree(project).write(probe / 'Probe.csproj', encoding='unicode')
    (probe / 'Program.cs').write_text('''
using ColDogStudios.ColDogLocker.Services.Lockers;
try
{
    using var lease = LockerOperationLease.Acquire(args[0]);
    Console.WriteLine("OWNED");
    if (args.Length > 1) Console.ReadLine();
    return 0;
}
catch (InvalidOperationException)
{
    Console.WriteLine("BUSY");
    return 2;
}
''', encoding='utf-8')
    subprocess.run(['dotnet', 'build', str(probe / 'Probe.csproj'), '-c', 'Release', '--nologo'],
                   check=True, timeout=120, capture_output=True, text=True)
    command = ['dotnet', str(probe / 'bin/Release/net10.0/Probe.dll'), str(uuid.uuid4())]
    owner = subprocess.Popen(command + ['hold'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        # Bound readiness by polling the pipe through a reader thread.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            ready = executor.submit(owner.stdout.readline)
            try:
                assert ready.result(timeout=15).strip() == 'OWNED'
            except BaseException:
                owner.kill()
                raise
        contender = subprocess.run(command, capture_output=True, text=True, timeout=15)
        assert contender.returncode == 2 and contender.stdout.strip() == 'BUSY', contender
        owner.communicate('\n', timeout=15)
        assert owner.returncode == 0
        successor = subprocess.run(command, capture_output=True, text=True, timeout=15)
        assert successor.returncode == 0 and successor.stdout.strip() == 'OWNED', successor
        print('PASS: independent processes contend and ownership is reusable after release')
    finally:
        if owner.poll() is None:
            owner.kill()
            owner.communicate(timeout=15)
