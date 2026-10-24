import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberGlintSafe {

    public void deleteAmberGlintAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        try {
            PreparedStatement amberGlintDelete = amberGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberGlintDelete.setString(1, data);
            if (authorized) {
                amberGlintDelete.executeUpdate();
            }
        } finally {
            amberGlintConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
