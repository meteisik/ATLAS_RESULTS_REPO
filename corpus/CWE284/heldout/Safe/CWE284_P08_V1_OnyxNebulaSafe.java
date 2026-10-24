import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxNebulaSafe {

    public void deleteOnyxNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_NEBULA_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxNebulaSafeSink()).applyOnyxNebulaDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxNebulaSafeSink {
    public void applyOnyxNebulaDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        try {
            PreparedStatement onyxNebulaDelete = onyxNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxNebulaDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxNebulaDelete.executeUpdate();
            }
        } finally {
            onyxNebulaConnection.close();
        }
    }
}
