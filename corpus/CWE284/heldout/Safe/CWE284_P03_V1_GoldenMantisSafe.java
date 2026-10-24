import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenMantisSafe {

    private void applyGoldenMantisDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
        try {
            PreparedStatement goldenMantisDelete = goldenMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenMantisDelete.setString(1, data);
            if (authorized) {
                goldenMantisDelete.executeUpdate();
            }
        } finally {
            goldenMantisConnection.close();
        }
    }

    public void deleteGoldenMantisAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_MANTIS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyGoldenMantisDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
