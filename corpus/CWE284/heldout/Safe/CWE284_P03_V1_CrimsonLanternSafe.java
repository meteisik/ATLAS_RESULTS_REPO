import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonLanternSafe {

    private void applyCrimsonLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLantern");
        try {
            PreparedStatement crimsonLanternDelete = crimsonLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonLanternDelete.setString(1, data);
            if (authorized) {
                crimsonLanternDelete.executeUpdate();
            }
        } finally {
            crimsonLanternConnection.close();
        }
    }

    public void deleteCrimsonLanternAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_LANTERN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyCrimsonLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
