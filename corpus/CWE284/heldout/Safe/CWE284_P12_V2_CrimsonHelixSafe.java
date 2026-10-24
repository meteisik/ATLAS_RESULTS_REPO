import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteCrimsonHelixAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("CRIMSON_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonHelixSafeBase baseObject = new CWE284_P12_V2_CrimsonHelixSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonHelixSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonHelixSafeRemover extends CWE284_P12_V2_CrimsonHelixSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHelix");
        try {
            PreparedStatement crimsonHelixDelete = crimsonHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonHelixDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonHelixDelete.executeUpdate();
            }
        } finally {
            crimsonHelixConnection.close();
        }
    }
}
