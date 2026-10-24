import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberAuroraSafe {

    public void deleteAmberAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_AURORA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        try {
            PreparedStatement amberAuroraDelete = amberAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberAuroraDelete.setString(1, data);
            if (authorized) {
                amberAuroraDelete.executeUpdate();
            }
        } finally {
            amberAuroraConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
