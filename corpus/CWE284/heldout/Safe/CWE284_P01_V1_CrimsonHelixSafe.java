import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CrimsonHelixSafe {

    public void deleteCrimsonHelixAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_HELIX_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection crimsonHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHelix");
        try {
            PreparedStatement crimsonHelixDelete = crimsonHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonHelixDelete.setString(1, data);
            if (authorized) {
                crimsonHelixDelete.executeUpdate();
            }
        } finally {
            crimsonHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
