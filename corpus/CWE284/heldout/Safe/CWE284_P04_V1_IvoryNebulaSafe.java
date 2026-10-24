import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryNebulaSafe {

    private boolean checkIvoryNebulaAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_NEBULA_ACCOUNT_ID");
        boolean authorized = checkIvoryNebulaAccess(data);
        Connection ivoryNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryNebula");
        try {
            PreparedStatement ivoryNebulaDelete = ivoryNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryNebulaDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryNebulaDelete.executeUpdate();
            }
        } finally {
            ivoryNebulaConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
