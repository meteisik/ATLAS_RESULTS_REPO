import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenGlint {

    private void applyGoldenGlintDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
        try {
            PreparedStatement goldenGlintDelete = goldenGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenGlintDelete.setString(1, data);
            if (authorized) {
                goldenGlintDelete.executeUpdate();
            }
        } finally {
            goldenGlintConnection.close();
        }
    }

    public void deleteGoldenGlintAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_GLINT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyGoldenGlintDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
