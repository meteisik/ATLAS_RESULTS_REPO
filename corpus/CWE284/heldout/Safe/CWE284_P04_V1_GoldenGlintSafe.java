import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenGlintSafe {

    private boolean checkGoldenGlintAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenGlintAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_GLINT_ACCOUNT_ID");
        boolean authorized = checkGoldenGlintAccess(data);
        Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
        try {
            PreparedStatement goldenGlintDelete = goldenGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenGlintDelete.executeUpdate();
            }
        } finally {
            goldenGlintConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
