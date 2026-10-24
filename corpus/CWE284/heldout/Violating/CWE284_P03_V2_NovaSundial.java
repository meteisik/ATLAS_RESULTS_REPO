import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_NovaSundial {

    private void applyNovaSundialDeletion(String data, boolean authorized) throws SQLException {
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
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("NOVA_SUNDIAL_ACCOUNT_ID");
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyNovaSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
