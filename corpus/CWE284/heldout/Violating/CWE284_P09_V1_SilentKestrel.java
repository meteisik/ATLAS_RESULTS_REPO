import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentKestrel {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_KESTREL_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentKestrelSink()).applySilentKestrelDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentKestrelSink {
    public void applySilentKestrelDeletion(CWE284_P09_V1_SilentKestrel.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentKestrel");
        try {
            PreparedStatement silentKestrelDelete = silentKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentKestrelDelete.setString(1, data);
            silentKestrelDelete.executeUpdate();
        } finally {
            silentKestrelConnection.close();
        }
    }
}
