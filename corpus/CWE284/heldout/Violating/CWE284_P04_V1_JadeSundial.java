import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeSundial {

    private boolean checkJadeSundialAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeSundialAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_SUNDIAL_ACCOUNT_ID");
        boolean authorized = checkJadeSundialAccess(data);
        Connection jadeSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSundial");
        try {
            PreparedStatement jadeSundialDelete = jadeSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSundialDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                jadeSundialDelete.executeUpdate();
            }
        } finally {
            jadeSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
