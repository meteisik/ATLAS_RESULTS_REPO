import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenFlare {

    private boolean checkGoldenFlareAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenFlareAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_FLARE_ACCOUNT_ID");
        boolean authorized = checkGoldenFlareAccess(data);
        Connection goldenFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenFlare");
        try {
            PreparedStatement goldenFlareDelete = goldenFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenFlareDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenFlareDelete.executeUpdate();
            }
        } finally {
            goldenFlareConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
