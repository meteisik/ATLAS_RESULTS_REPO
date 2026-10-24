import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteVelvetSundialAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("VELVET_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetSundialSink()).applyVelvetSundialDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetSundialSink {
    public void applyVelvetSundialDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        try {
            PreparedStatement velvetSundialDelete = velvetSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSundialDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetSundialDelete.executeUpdate();
            }
        } finally {
            velvetSundialConnection.close();
        }
    }
}
