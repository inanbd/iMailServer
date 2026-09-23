using System.Reflection;
using System.Text.RegularExpressions;

namespace MailServer.Domain.Tests;

/// <summary>
/// The admin console's wiring, checked from its source because the console itself cannot run
/// here.
/// </summary>
/// <remarks>
/// <para>
/// The console is WPF, so no test on the build machine can load it, and a XAML binding to a
/// command that does not exist is not a compile error: WPF logs a binding failure nobody reads
/// and the button does nothing. The Quarantine page shipped exactly that - a Refresh button
/// bound to a command its view model never defined - and it was found by reading the source.
/// These read the source instead, so the next one is found by the build.
/// </para>
/// <para>
/// Deliberately narrow. They match the idioms this project uses - <c>[RelayCommand]</c> on a
/// method, a <c>d:DesignInstance</c> naming each page's view model, one <c>DataTemplate</c>
/// per page - rather than parsing XAML in general, and a page written some other way should
/// be made to follow the idioms rather than this be made to understand it.
/// </para>
/// </remarks>
public sealed class AdminConsoleWiringTests
{
    private static readonly string AdminRoot = Path.Combine(FindRepositoryRoot(), "src", "MailServer.Admin");

    public static TheoryData<string> Pages()
    {
        TheoryData<string> pages = [];

        foreach (string page in Directory.EnumerateFiles(Path.Combine(AdminRoot, "Views", "Pages"), "*.xaml"))
        {
            pages.Add(Path.GetFileName(page));
        }

        return pages;
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void Every_command_a_page_binds_is_defined_on_its_view_model(string page)
    {
        string xaml = File.ReadAllText(Path.Combine(AdminRoot, "Views", "Pages", page));

        Match designInstance = Regex.Match(xaml, @"d:DesignInstance\s+Type=vm:(\w+)");
        designInstance.Success.ShouldBeTrue($"{page} names no view model with d:DesignInstance.");

        string viewModel = designInstance.Groups[1].Value;
        string body = ViewModelSource(viewModel);

        // Plain {Binding XCommand} only: a command reached through RelativeSource or ElementName
        // is bound to some other object and is not this page's view model's to define.
        string[] missing =
        [
            .. Regex.Matches(xaml, @"\{Binding\s+(\w+)Command[\s,}]")
                .Select(m => m.Groups[1].Value)
                .Distinct()
                .Where(command => !Regex.IsMatch(
                    body,
                    $@"\[RelayCommand[^\]]*\]\s*(?:(?:private|public|internal|protected|async)\s+)+[\w<>?,\s]+\s{command}(?:Async)?\("))
                .Select(command => command + "Command"),
        ];

        missing.ShouldBeEmpty(
            $"{page} binds commands {viewModel} never defines; WPF would render the button and it would do nothing.");
    }

    [Fact]
    public void Every_page_in_the_navigation_has_a_view_and_a_registration()
    {
        string shell = File.ReadAllText(Path.Combine(AdminRoot, "ViewModels", "ShellViewModel.cs"));
        string templates = File.ReadAllText(Path.Combine(AdminRoot, "App.xaml"));
        string registrations = File.ReadAllText(Path.Combine(AdminRoot, "App.xaml.cs"));

        // Entries marked unavailable borrow some other page's type as a placeholder; only the
        // ones an operator can open have to resolve.
        string[] available =
        [
            .. Regex.Matches(shell, @"new\(""[^""]+"",\s*""[^""]+"",\s*typeof\((\w+)\)\)")
                .Select(m => m.Groups[1].Value)
                .Distinct(),
        ];

        available.ShouldNotBeEmpty("The navigation tree was not found; this test has lost track of the source.");

        foreach (string viewModel in available)
        {
            templates.ShouldContain(
                $"DataType=\"{{x:Type vm:{viewModel}}}\"",
                customMessage: $"{viewModel} is in the navigation but App.xaml has no template to render it.");

            Regex.IsMatch(registrations, $@"Add(?:Transient|Singleton|Scoped)<{viewModel}>").ShouldBeTrue(
                $"{viewModel} is in the navigation but App.xaml.cs never registers it, so navigating to it fails.");
        }
    }

    /// <summary>The source of one view model class, from its declaration to the next one.</summary>
    /// <remarks>
    /// Sliced rather than the whole file, because some files hold several view models and a
    /// command defined on a neighbour must not count as defined on this one.
    /// </remarks>
    private static string ViewModelSource(string viewModel)
    {
        foreach (string file in Directory.EnumerateFiles(Path.Combine(AdminRoot, "ViewModels"), "*.cs"))
        {
            string source = File.ReadAllText(file);
            Match declaration = Regex.Match(source, $@"\bclass\s+{viewModel}\b");

            if (!declaration.Success)
            {
                continue;
            }

            Match next = Regex.Match(source[(declaration.Index + declaration.Length)..], @"\n(?:public|internal)\s[^\n]*\bclass\s");

            return next.Success
                ? source.Substring(declaration.Index, declaration.Length + next.Index)
                : source[declaration.Index..];
        }

        throw new InvalidOperationException($"No source declares {viewModel}.");
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "MailServer.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("MailServer.sln was not found above the test assembly.");
    }
}
