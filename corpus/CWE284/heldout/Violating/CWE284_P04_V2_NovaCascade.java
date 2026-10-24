import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_NovaCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private boolean checkNovaCascadeAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteNovaCascadeAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("NOVA_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkNovaCascadeAccess(data);
        Connection novaCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaCascade");
        try {
            PreparedStatement novaCascadeDelete = novaCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaCascadeDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaCascadeDelete.executeUpdate();
            }
        } finally {
            novaCascadeConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
