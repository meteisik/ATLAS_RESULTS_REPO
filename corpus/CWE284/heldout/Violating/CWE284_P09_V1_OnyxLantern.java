import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxLantern {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxLanternAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_LANTERN_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxLanternSink()).applyOnyxLanternDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxLanternSink {
    public void applyOnyxLanternDeletion(CWE284_P09_V1_OnyxLantern.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        try {
            PreparedStatement onyxLanternDelete = onyxLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLanternDelete.setString(1, data);
            onyxLanternDelete.executeUpdate();
        } finally {
            onyxLanternConnection.close();
        }
    }
}
