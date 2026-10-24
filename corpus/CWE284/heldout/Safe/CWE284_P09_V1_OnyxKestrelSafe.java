import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxKestrelSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_KESTREL_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxKestrelSafeSink()).applyOnyxKestrelDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxKestrelSafeSink {
    public void applyOnyxKestrelDeletion(CWE284_P09_V1_OnyxKestrelSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        try {
            PreparedStatement onyxKestrelDelete = onyxKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxKestrelDelete.setString(1, data);
            if (authorized) {
                onyxKestrelDelete.executeUpdate();
            }
        } finally {
            onyxKestrelConnection.close();
        }
    }
}
