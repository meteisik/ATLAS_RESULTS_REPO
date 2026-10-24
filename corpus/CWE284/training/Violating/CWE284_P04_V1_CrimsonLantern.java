import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_CrimsonLantern {

    private boolean checkCrimsonLanternAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteCrimsonLanternAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_LANTERN_ACCOUNT_ID");
        boolean authorized = checkCrimsonLanternAccess(data);
        Connection crimsonLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLantern");
        try {
            PreparedStatement crimsonLanternDelete = crimsonLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonLanternDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
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
