import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_CrimsonLanternSafe {

    public void deleteCrimsonLanternAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("CRIMSON_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
