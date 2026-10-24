import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeGlint {

    public void deleteJadeGlintAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("JADE_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
        try {
            PreparedStatement jadeGlintDelete = jadeGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeGlintDelete.setString(1, data);
            jadeGlintDelete.executeUpdate();
        } finally {
            jadeGlintConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
