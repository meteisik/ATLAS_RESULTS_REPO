import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_GoldenFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteGoldenFlareAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_GoldenFlareSafeBase baseObject = new CWE284_P12_V2_GoldenFlareSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_GoldenFlareSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_GoldenFlareSafeRemover extends CWE284_P12_V2_GoldenFlareSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection goldenFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenFlare");
        try {
            PreparedStatement goldenFlareDelete = goldenFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenFlareDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenFlareDelete.executeUpdate();
            }
        } finally {
            goldenFlareConnection.close();
        }
    }
}
