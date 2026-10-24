import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ArcticHarborSafe {

    public void deleteArcticHarborAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HARBOR_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ArcticHarborSafeBase baseObject = new CWE284_P12_V1_ArcticHarborSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ArcticHarborSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ArcticHarborSafeRemover extends CWE284_P12_V1_ArcticHarborSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        try {
            PreparedStatement arcticHarborDelete = arcticHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHarborDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticHarborDelete.executeUpdate();
            }
        } finally {
            arcticHarborConnection.close();
        }
    }
}
