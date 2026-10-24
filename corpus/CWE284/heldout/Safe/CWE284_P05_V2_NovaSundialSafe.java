import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_NovaSundialSafe {
    private static boolean privateTrue = true;

    private String novaSundialAccountId;

    private boolean novaSundialAuthorized;

    private void applyNovaSundialDeletion() throws SQLException {
        String data = novaSundialAccountId;
        boolean authorized = novaSundialAuthorized;
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        try {
            PreparedStatement novaSundialDelete = novaSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSundialDelete.setString(1, data);
            if (authorized) {
                novaSundialDelete.executeUpdate();
            }
        } finally {
            novaSundialConnection.close();
        }
    }

    public void deleteNovaSundialAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("NOVA_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        novaSundialAccountId = data;
        novaSundialAuthorized = isAuthorized(data);
        applyNovaSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
