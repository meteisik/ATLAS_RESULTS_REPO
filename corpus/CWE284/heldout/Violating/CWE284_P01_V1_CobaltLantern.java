import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CobaltLantern {

    public void deleteCobaltLanternAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_LANTERN_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection cobaltLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLantern");
        try {
            PreparedStatement cobaltLanternDelete = cobaltLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltLanternDelete.setString(1, data);
            cobaltLanternDelete.executeUpdate();
        } finally {
            cobaltLanternConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
