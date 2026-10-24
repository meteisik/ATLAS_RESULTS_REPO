import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonHelix {

    private void applyCrimsonHelixDeletion(String data, boolean authorized) throws SQLException {
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

    public void deleteCrimsonHelixAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_HELIX_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCrimsonHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
