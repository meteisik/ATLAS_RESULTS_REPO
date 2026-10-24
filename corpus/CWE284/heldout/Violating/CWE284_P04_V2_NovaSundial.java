import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_NovaSundial {

    private boolean checkNovaSundialAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteNovaSundialAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("NOVA_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkNovaSundialAccess(data);
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        try {
            PreparedStatement novaSundialDelete = novaSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSundialDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaSundialDelete.executeUpdate();
            }
        } finally {
            novaSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
