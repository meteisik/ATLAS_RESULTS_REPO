import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxHelix {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxHelixAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_HELIX_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxHelixSink()).applyOnyxHelixDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxHelixSink {
    public void applyOnyxHelixDeletion(CWE284_P09_V1_OnyxHelix.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        try {
            PreparedStatement onyxHelixDelete = onyxHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHelixDelete.setString(1, data);
            onyxHelixDelete.executeUpdate();
        } finally {
            onyxHelixConnection.close();
        }
    }
}
