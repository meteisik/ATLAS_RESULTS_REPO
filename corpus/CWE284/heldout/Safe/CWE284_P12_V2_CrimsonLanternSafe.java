import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteCrimsonLanternAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("CRIMSON_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonLanternSafeBase baseObject = new CWE284_P12_V2_CrimsonLanternSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonLanternSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonLanternSafeRemover extends CWE284_P12_V2_CrimsonLanternSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLantern");
        try {
            PreparedStatement crimsonLanternDelete = crimsonLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonLanternDelete.executeUpdate();
            }
        } finally {
            crimsonLanternConnection.close();
        }
    }
}
