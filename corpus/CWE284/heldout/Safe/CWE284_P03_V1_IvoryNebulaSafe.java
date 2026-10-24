import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryNebulaSafe {

    private void applyIvoryNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryNebula");
        try {
            PreparedStatement ivoryNebulaDelete = ivoryNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryNebulaDelete.setString(1, data);
            if (authorized) {
                ivoryNebulaDelete.executeUpdate();
            }
        } finally {
            ivoryNebulaConnection.close();
        }
    }

    public void deleteIvoryNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_NEBULA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyIvoryNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
