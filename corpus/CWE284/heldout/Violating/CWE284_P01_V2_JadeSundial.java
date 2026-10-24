import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeSundial {
    private static int privateFive = 5;

    public void deleteJadeSundialAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("JADE_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection jadeSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSundial");
        try {
            PreparedStatement jadeSundialDelete = jadeSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSundialDelete.setString(1, data);
            jadeSundialDelete.executeUpdate();
        } finally {
            jadeSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
