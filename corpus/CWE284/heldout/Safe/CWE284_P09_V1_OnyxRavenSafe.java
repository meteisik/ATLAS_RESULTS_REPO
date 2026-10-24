import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxRavenSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxRavenAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_RAVEN_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxRavenSafeSink()).applyOnyxRavenDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxRavenSafeSink {
    public void applyOnyxRavenDeletion(CWE284_P09_V1_OnyxRavenSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        try {
            PreparedStatement onyxRavenDelete = onyxRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxRavenDelete.setString(1, data);
            if (authorized) {
                onyxRavenDelete.executeUpdate();
            }
        } finally {
            onyxRavenConnection.close();
        }
    }
}
