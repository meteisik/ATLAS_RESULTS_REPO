import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteCrimsonKestrelAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonKestrelBase baseObject = new CWE284_P12_V2_CrimsonKestrelRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonKestrelBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonKestrelRemover extends CWE284_P12_V2_CrimsonKestrelBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonKestrel");
        try {
            PreparedStatement crimsonKestrelDelete = crimsonKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonKestrelDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonKestrelDelete.executeUpdate();
            }
        } finally {
            crimsonKestrelConnection.close();
        }
    }
}
