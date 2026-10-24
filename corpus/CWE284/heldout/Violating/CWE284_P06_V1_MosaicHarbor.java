import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicHarbor {

    public void deleteMosaicHarborAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HARBOR_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicHarborSink()).applyMosaicHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicHarborSink {
    public void applyMosaicHarborDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHarbor");
        try {
            PreparedStatement mosaicHarborDelete = mosaicHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHarborDelete.setString(1, data);
            mosaicHarborDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicHarborConnection.close();
        }
    }
}
