import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteCrimsonHarborAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("CRIMSON_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonHarborBase baseObject = new CWE284_P12_V2_CrimsonHarborRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonHarborBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonHarborRemover extends CWE284_P12_V2_CrimsonHarborBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHarbor");
        try {
            PreparedStatement crimsonHarborDelete = crimsonHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonHarborDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonHarborDelete.executeUpdate();
            }
        } finally {
            crimsonHarborConnection.close();
        }
    }
}
