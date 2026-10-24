import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteGoldenCipherAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("GOLDEN_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        try {
            PreparedStatement goldenCipherDelete = goldenCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCipherDelete.setString(1, data);
            if (authorized) {
                goldenCipherDelete.executeUpdate();
            }
        } finally {
            goldenCipherConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
