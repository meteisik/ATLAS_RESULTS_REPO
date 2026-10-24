import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_GoldenCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteGoldenCascadeAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_GoldenCascadeSafeBase baseObject = new CWE284_P12_V2_GoldenCascadeSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_GoldenCascadeSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_GoldenCascadeSafeRemover extends CWE284_P12_V2_GoldenCascadeSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection goldenCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCascade");
        try {
            PreparedStatement goldenCascadeDelete = goldenCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCascadeDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenCascadeDelete.executeUpdate();
            }
        } finally {
            goldenCascadeConnection.close();
        }
    }
}
