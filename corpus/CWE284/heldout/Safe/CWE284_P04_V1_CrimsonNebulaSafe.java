import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_CrimsonNebulaSafe {

    private boolean checkCrimsonNebulaAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteCrimsonNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_NEBULA_ACCOUNT_ID");
        boolean authorized = checkCrimsonNebulaAccess(data);
        Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
        try {
            PreparedStatement crimsonNebulaDelete = crimsonNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonNebulaDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonNebulaDelete.executeUpdate();
            }
        } finally {
            crimsonNebulaConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
