import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteGoldenCascadeAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection goldenCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCascade");
        try {
            PreparedStatement goldenCascadeDelete = goldenCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCascadeDelete.setString(1, data);
            if (authorized) {
                goldenCascadeDelete.executeUpdate();
            }
        } finally {
            goldenCascadeConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
