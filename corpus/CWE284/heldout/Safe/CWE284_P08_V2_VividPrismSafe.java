import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VividPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteVividPrismAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("VIVID_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VividPrismSafeSink()).applyVividPrismDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VividPrismSafeSink {
    public void applyVividPrismDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        try {
            PreparedStatement vividPrismDelete = vividPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividPrismDelete.executeUpdate();
            }
        } finally {
            vividPrismConnection.close();
        }
    }
}
