import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ArcticComet {

    public void deleteArcticCometAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_COMET_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ArcticCometBase baseObject = new CWE284_P12_V1_ArcticCometRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ArcticCometBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ArcticCometRemover extends CWE284_P12_V1_ArcticCometBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        try {
            PreparedStatement arcticCometDelete = arcticCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticCometDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticCometDelete.executeUpdate();
            }
        } finally {
            arcticCometConnection.close();
        }
    }
}
