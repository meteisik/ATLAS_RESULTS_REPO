import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenAuroraSafe {

    private boolean checkGoldenAuroraAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_AURORA_ACCOUNT_ID");
        boolean authorized = checkGoldenAuroraAccess(data);
        Connection goldenAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenAurora");
        try {
            PreparedStatement goldenAuroraDelete = goldenAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenAuroraDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenAuroraDelete.executeUpdate();
            }
        } finally {
            goldenAuroraConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
