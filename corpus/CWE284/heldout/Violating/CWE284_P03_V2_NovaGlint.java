import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_NovaGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void applyNovaGlintDeletion(String data, boolean authorized) throws SQLException {
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        try {
            PreparedStatement novaGlintDelete = novaGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaGlintDelete.setString(1, data);
            if (authorized) {
                novaGlintDelete.executeUpdate();
            }
        } finally {
            novaGlintConnection.close();
        }
    }

    public void deleteNovaGlintAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("NOVA_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyNovaGlintDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
