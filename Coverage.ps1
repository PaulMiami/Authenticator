$testProjectLocations = @('test/Authentication.Authenticator.Test', 'test/Identity.Authenticator.Test', 'test/Identity.Authenticator.EntityFrameworkCore.Test')
$outputLocation = 'testResults'
iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/PaulMiami/BuildTools/821f43d8740045dff991e1bf2f3f6ce83fa7c626/Coverage.ps1'))
