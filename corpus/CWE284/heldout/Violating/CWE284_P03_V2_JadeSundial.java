import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadeSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void applyJadeSundialDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSundial");
        try {
            PreparedStatement jadeSundialDelete = jadeSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSundialDelete.setString(1, data);
            if (authorized) {
                jadeSundialDelete.executeUpdate();
            }
        } finally {
            jadeSundialConnection.close();
        }
    }

    public void deleteJadeSundialAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("JADE_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyJadeSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
