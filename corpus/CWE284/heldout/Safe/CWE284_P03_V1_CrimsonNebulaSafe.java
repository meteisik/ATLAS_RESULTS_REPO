import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonNebulaSafe {

    private void applyCrimsonNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
        try {
            PreparedStatement crimsonNebulaDelete = crimsonNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonNebulaDelete.setString(1, data);
            if (authorized) {
                crimsonNebulaDelete.executeUpdate();
            }
        } finally {
            crimsonNebulaConnection.close();
        }
    }

    public void deleteCrimsonNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_NEBULA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyCrimsonNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
