import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaSundialSafe {

    public void deleteNovaSundialAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaSundialSafeSink()).applyNovaSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaSundialSafeSink {
    public void applyNovaSundialDeletion(String data, boolean authorized) throws SQLException {
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        try {
            PreparedStatement novaSundialDelete = novaSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSundialDelete.setString(1, data);
            if (authorized) {
                novaSundialDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaSundialConnection.close();
        }
    }
}
