import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxNebulaSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_NEBULA_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxNebulaSafeSink()).applyOnyxNebulaDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxNebulaSafeSink {
    public void applyOnyxNebulaDeletion(CWE284_P09_V1_OnyxNebulaSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        try {
            PreparedStatement onyxNebulaDelete = onyxNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxNebulaDelete.setString(1, data);
            if (authorized) {
                onyxNebulaDelete.executeUpdate();
            }
        } finally {
            onyxNebulaConnection.close();
        }
    }
}
