# The Lab
TODO

# Testapp
A bare minimum .NET Framework 4.6.1 ASP.NET application. It is meant to represent a legacy web application running in an AD DS environment. The application is meant to be run with Windows Authentication under IIS. It only has 2 paths. `GET /` returns a simple HTML page and `GET /api` which returns a JSON document with authenticated user information.

This is the source for `testapp.zip` in the [lab_artifacts release](https://github.com/wpbrown/oakproxy/releases/tag/lab_artifacts). This is automatically deployed to the "The Lab" above.

# Testimper
A testing tool with .NET Framework and .NET Core builds to test Kerberos S4U2Self impersonation. It has options to use WinHttp or the new SocketsHandler in .NET Core and to manipulate whether the TCB and Impersonation privileges are enabled. Example output [here](https://github.com/wpbrown/oakproxy/blob/master/testenv/testimper/output.log).

# Testasync
A .NET Core app for testing async and impersonation. It demonstrates that the impersonation context is being migrated to the thread by the Async execution context. Example output [here](https://github.com/wpbrown/oakproxy/blob/master/testenv/testasync/output.log).
