import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenFlare {

    private void applyGoldenFlareDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenFlare");
        try {
            PreparedStatement goldenFlareDelete = goldenFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenFlareDelete.setString(1, data);
            if (authorized) {
                goldenFlareDelete.executeUpdate();
            }
        } finally {
            goldenFlareConnection.close();
        }
    }

    public void deleteGoldenFlareAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_FLARE_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyGoldenFlareDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
